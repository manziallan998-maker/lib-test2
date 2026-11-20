import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'OPTIONS, POST, GET',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

const jsonResponse = (body: Record<string, unknown>, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (req.method !== 'POST') return jsonResponse({ success: false, error: 'Method not allowed' }, 405)

  let createdUserId: string | null = null
  let createdSchoolId: number | null = null

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return jsonResponse({ success: false, error: 'Unauthorized' }, 401)
    }
    const token = authHeader.slice('Bearer '.length)

    // Validate the caller's identity and super-admin role using their own JWT.
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    )
    const { data: { user }, error: userErr } = await supabase.auth.getUser()
    if (userErr || !user) return jsonResponse({ success: false, error: 'Unauthorized' }, 401)

    const { data: adminData, error: adminErr } = await supabase
      .from('admins').select('role').eq('id', user.id).maybeSingle()
    if (adminErr || adminData?.role !== 'super_admin') {
      return jsonResponse({ success: false, error: 'Forbidden: Super Admin role required' }, 403)
    }

    const body = await req.json().catch(() => null)
    const requestId = Number(body?.request_id)
    if (!Number.isSafeInteger(requestId) || requestId <= 0) {
      return jsonResponse({ success: false, error: 'A valid request_id is required' }, 400)
    }

    const serviceRoleClient = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SERVICE_ROLE_KEY')!,
      { auth: { autoRefreshToken: false, persistSession: false } },
    )

    // Lock logically by only proceeding with the pending request and requiring
    // an approved payment link plus an approved payment record before provisioning.
    const { data: reqData, error: reqErr } = await serviceRoleClient
      .from('registration_requests')
      .select('*')
      .eq('id', requestId)
      .eq('status', 'pending')
      .maybeSingle()
    if (reqErr || !reqData) {
      return jsonResponse({ success: false, error: 'Request not found or already processed' }, 404)
    }

    const { data: paymentLink, error: linkErr } = await serviceRoleClient
      .from('registration_payment_links')
      .select('payment_id, payment_status')
      .eq('registration_request_id', requestId)
      .eq('payment_status', 'approved')
      .maybeSingle()
    if (linkErr) {
      console.error('Payment link lookup failed:', linkErr.message)
      return jsonResponse({ success: false, error: 'Could not verify the linked payment' }, 500)
    }
    if (!paymentLink?.payment_id) {
      return jsonResponse({ success: false, error: 'Registration cannot be approved until an approved payment is linked' }, 409)
    }

    const { data: payment, error: paymentErr } = await serviceRoleClient
      .from('payments')
      .select('id, status')
      .eq('id', paymentLink.payment_id)
      .maybeSingle()
    if (paymentErr) {
      console.error('Payment status lookup failed:', paymentErr.message)
      return jsonResponse({ success: false, error: 'Could not verify payment status' }, 500)
    }
    if (!payment || payment.status !== 'approved') {
      return jsonResponse({ success: false, error: 'The linked payment is not approved' }, 409)
    }

    // Generate credentials only after all authorization, request, and payment checks pass.
    const schoolCode = 'SCH-' + crypto.randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase()
    const tempPassword = 'School@' + crypto.randomUUID().replaceAll('-', '').slice(0, 12)

    const { data: authUser, error: createUserErr } = await serviceRoleClient.auth.admin.createUser({
      email: reqData.contact_email,
      password: tempPassword,
      email_confirm: true,
      user_metadata: { full_name: reqData.head_teacher_name },
    })
    if (createUserErr || !authUser.user) {
      console.error('Auth user creation failed:', createUserErr?.message)
      return jsonResponse({ success: false, error: `Auth Error: ${createUserErr?.message || 'User creation failed'}` }, 500)
    }
    createdUserId = authUser.user.id

    const { data: newSchool, error: schoolErr } = await serviceRoleClient
      .from('schools')
      .insert({ name: reqData.school_name, school_code: schoolCode })
      .select('id')
      .single()
    if (schoolErr || !newSchool) {
      await serviceRoleClient.auth.admin.deleteUser(createdUserId)
      createdUserId = null
      console.error('School creation failed:', schoolErr?.message)
      return jsonResponse({ success: false, error: `School Creation Error: ${schoolErr?.message || 'School creation failed'}` }, 500)
    }
    createdSchoolId = newSchool.id

    const { error: adminInsertErr } = await serviceRoleClient.from('admins').insert({
      id: authUser.user.id,
      email: reqData.contact_email,
      full_name: reqData.head_teacher_name,
      role: 'admin',
      school_id: newSchool.id,
    })
    if (adminInsertErr) {
      await serviceRoleClient.auth.admin.deleteUser(createdUserId)
      await serviceRoleClient.from('schools').delete().eq('id', createdSchoolId)
      createdUserId = null
      createdSchoolId = null
      console.error('Admin record creation failed:', adminInsertErr.message)
      return jsonResponse({ success: false, error: `Admin Insert Error: ${adminInsertErr.message}` }, 500)
    }

    const { data: updatedRequest, error: updateErr } = await serviceRoleClient
      .from('registration_requests')
      .update({ status: 'approved', decided_at: new Date().toISOString(), decided_by: user.id })
      .eq('id', requestId)
      .eq('status', 'pending')
      .select('id')
      .maybeSingle()
    if (updateErr || !updatedRequest) {
      // Roll back provisioning if the request could not be transitioned.
      await serviceRoleClient.from('admins').delete().eq('id', createdUserId)
      await serviceRoleClient.auth.admin.deleteUser(createdUserId)
      await serviceRoleClient.from('schools').delete().eq('id', createdSchoolId)
      createdUserId = null
      createdSchoolId = null
      console.error('Registration status update failed:', updateErr?.message)
      return jsonResponse({ success: false, error: 'Registration status could not be updated; provisioning was rolled back' }, 500)
    }

    const { error: auditErr } = await serviceRoleClient.from('platform_audit_log').insert({
      actor_id: user.id,
      actor_label: user.email,
      action: 'approve_school',
      target_request_id: requestId,
      target_school_id: newSchool.id,
      detail: { school_code: schoolCode, payment_id: payment.id },
    })
    if (auditErr) console.warn('Approval audit log insert failed:', auditErr.message)

    return jsonResponse({
      success: true,
      school_code: schoolCode,
      admin_email: reqData.contact_email,
      temp_password: tempPassword,
    })
  } catch (error) {
    console.error('approve-registration failed:', error)
    return jsonResponse({ success: false, error: error instanceof Error ? error.message : 'Unexpected server error' }, 500)
  }
})
