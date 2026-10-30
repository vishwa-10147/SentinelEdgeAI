import React, { useEffect, useState } from 'react'
import { changePassword, enableMfa, errorMessage, login, startMfaSetup } from '../api'

export function AuthCard({ title, subtitle, children }){
  return (
    <div className="auth-screen">
      <section className="auth-card">
        <div className="brand-block">
          <div className="shield-logo">S</div>
          <div>
            <div className="wordmark">SentinelEdgeAI</div>
            <div className="auth-subtitle">Network detection and response console</div>
          </div>
        </div>
        <h1>{title}</h1>
        {subtitle && <p className="auth-hint">{subtitle}</p>}
        {children}
      </section>
    </div>
  )
}

export function LoginScreen({ onSignedIn }){
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [needCode, setNeedCode] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event)=>{
    event.preventDefault()
    setBusy(true)
    setError('')
    try{
      const user = await login(username.trim(), password, needCode ? otp.trim() : undefined)
      setPassword('')
      setOtp('')
      onSignedIn(user)
    }catch(e){
      const detail = e?.response?.data?.detail
      if(detail === 'mfa_required'){
        setNeedCode(true)
      }else if(detail === 'mfa_invalid'){
        setOtp('')
        setError('That code is not valid. Enter the current code from your app, or a recovery code.')
      }else{
        setError(errorMessage(e, 'Sign-in failed'))
      }
    }finally{
      setBusy(false)
    }
  }

  const startOver = ()=>{
    setNeedCode(false)
    setOtp('')
    setPassword('')
    setError('')
  }

  if(needCode){
    return (
      <AuthCard title="Two-step sign-in" subtitle={`Enter the 6-digit code from the authenticator app for ${username.trim()}.`}>
        <form className="auth-form" onSubmit={submit}>
          <label htmlFor="login-otp">Authenticator code</label>
          <input id="login-otp" className="otp-input" inputMode="numeric" autoComplete="one-time-code" autoFocus value={otp} onChange={e=>setOtp(e.target.value)} />
          <p className="auth-hint">Lost your phone? Enter one of your recovery codes instead.</p>
          {error && <div className="auth-error" role="alert">{error}</div>}
          <button className="primary-button" type="submit" disabled={busy || otp.trim().length < 6}>{busy ? 'Checking…' : 'Verify'}</button>
          <button className="ghost-button" type="button" onClick={startOver}>Use a different account</button>
        </form>
      </AuthCard>
    )
  }

  return (
    <AuthCard title="Sign in">
      <form className="auth-form" onSubmit={submit}>
        <label htmlFor="login-username">Username</label>
        <input id="login-username" autoComplete="username" autoFocus value={username} onChange={e=>setUsername(e.target.value)} />
        <label htmlFor="login-password">Password</label>
        <input id="login-password" type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} />
        {error && <div className="auth-error" role="alert">{error}</div>}
        <button className="primary-button" type="submit" disabled={busy || !username || !password}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </AuthCard>
  )
}

export function ChangePasswordScreen({ user, minLength = 12, onChanged, onCancel }){
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [repeat, setRepeat] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const mismatch = repeat && next !== repeat

  const submit = async (event)=>{
    event.preventDefault()
    if(next !== repeat) return
    setBusy(true)
    setError('')
    try{
      await changePassword(current, next)
      onChanged()
    }catch(e){
      setError(errorMessage(e, 'Password change failed'))
    }finally{
      setBusy(false)
    }
  }

  return (
    <AuthCard
      title="Choose a new password"
      subtitle={user?.must_change_password
        ? `Signed in as ${user.username}. You must set your own password before using the console.`
        : `Signed in as ${user?.username}. Other sessions will be signed out.`}
    >
      <form className="auth-form" onSubmit={submit}>
        <label htmlFor="pw-current">Current password</label>
        <input id="pw-current" type="password" autoComplete="current-password" autoFocus value={current} onChange={e=>setCurrent(e.target.value)} />
        <label htmlFor="pw-new">New password (at least {minLength} characters)</label>
        <input id="pw-new" type="password" autoComplete="new-password" value={next} onChange={e=>setNext(e.target.value)} />
        <label htmlFor="pw-repeat">Repeat new password</label>
        <input id="pw-repeat" type="password" autoComplete="new-password" value={repeat} onChange={e=>setRepeat(e.target.value)} />
        {mismatch && <div className="auth-error">Passwords do not match</div>}
        {error && <div className="auth-error" role="alert">{error}</div>}
        <button className="primary-button" type="submit" disabled={busy || !current || next.length < minLength || next !== repeat}>
          {busy ? 'Saving…' : 'Change password'}
        </button>
        {onCancel && <button className="ghost-button" type="button" onClick={onCancel}>{user?.must_change_password ? 'Sign out' : 'Cancel'}</button>}
      </form>
    </AuthCard>
  )
}

export function MfaSetupScreen({ user, onDone, onSignOut }){
  const [enrolment, setEnrolment] = useState(null)
  const [code, setCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState(null)
  const [saved, setSaved] = useState(false)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(()=>{
    startMfaSetup()
      .then(setEnrolment)
      .catch(e=>setError(errorMessage(e, 'Could not start two-step sign-in setup')))
  }, [])

  const verify = async (event)=>{
    event.preventDefault()
    setBusy(true)
    setError('')
    try{
      const result = await enableMfa(code.trim())
      setRecoveryCodes(result.recovery_codes)
    }catch(e){
      setError(errorMessage(e, 'Code not accepted'))
    }finally{
      setBusy(false)
    }
  }

  const codesText = ()=>[
    `SentinelEdgeAI recovery codes for ${user?.username}`,
    'Each code works once. Keep them somewhere safe and offline.',
    '',
    ...(recoveryCodes || [])
  ].join('\n')

  const copy = async ()=>{
    try{
      await navigator.clipboard.writeText(codesText())
      setCopied(true)
    }catch(e){
      setError('Copy failed; use Download instead')
    }
  }

  const download = ()=>{
    const url = URL.createObjectURL(new Blob([codesText() + '\n'], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `sentineledgeai-recovery-codes-${user?.username}.txt`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  if(recoveryCodes){
    return (
      <AuthCard title="Save your recovery codes" subtitle="If you lose your phone, each of these codes lets you sign in once. They will not be shown again.">
        <div className="recovery-codes" aria-label="Recovery codes">
          {recoveryCodes.map(c=><code key={c}>{c}</code>)}
        </div>
        <div className="auth-row">
          <button className="ghost-button" type="button" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
          <button className="ghost-button" type="button" onClick={download}>Download</button>
        </div>
        {error && <div className="auth-error" role="alert">{error}</div>}
        <label className="auth-check">
          <input type="checkbox" checked={saved} onChange={e=>setSaved(e.target.checked)} />
          I saved my recovery codes
        </label>
        <button className="primary-button" type="button" disabled={!saved} onClick={onDone}>Continue to the console</button>
      </AuthCard>
    )
  }

  return (
    <AuthCard
      title="Set up two-step sign-in"
      subtitle={`Your role (${user?.role}) can change the firewall, so sign-in needs a code from an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Aegis…).`}
    >
      {enrolment ? (
        <>
          <ol className="auth-steps">
            <li>Scan this QR code with your authenticator app.</li>
            <li>Enter the 6-digit code it shows.</li>
          </ol>
          <img
            className="mfa-qr"
            alt="QR code for your authenticator app"
            src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(enrolment.qr_svg)}`}
          />
          <details className="mfa-manual">
            <summary>Can't scan? Enter the key manually</summary>
            <code>{enrolment.secret.match(/.{1,4}/g).join(' ')}</code>
            <p className="auth-hint">Type: time-based · 6 digits · 30 seconds</p>
          </details>
          <form className="auth-form" onSubmit={verify}>
            <label htmlFor="mfa-code">Code from your app</label>
            <input id="mfa-code" className="otp-input" inputMode="numeric" autoComplete="one-time-code" autoFocus value={code} onChange={e=>setCode(e.target.value)} />
            {error && <div className="auth-error" role="alert">{error}</div>}
            <button className="primary-button" type="submit" disabled={busy || code.trim().length < 6}>{busy ? 'Checking…' : 'Turn on two-step sign-in'}</button>
            <button className="ghost-button" type="button" onClick={onSignOut}>Sign out</button>
          </form>
        </>
      ) : (
        <>
          {error ? <div className="auth-error" role="alert">{error}</div> : <p className="auth-hint">Preparing…</p>}
          <button className="ghost-button" type="button" onClick={onSignOut}>Sign out</button>
        </>
      )}
    </AuthCard>
  )
}
