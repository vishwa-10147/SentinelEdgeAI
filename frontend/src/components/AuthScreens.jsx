import React, { useState } from 'react'
import { changePassword, errorMessage, login } from '../api'

function AuthCard({ title, subtitle, children }){
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
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event)=>{
    event.preventDefault()
    setBusy(true)
    setError('')
    try{
      const user = await login(username.trim(), password)
      setPassword('')
      onSignedIn(user)
    }catch(e){
      setError(errorMessage(e, 'Sign-in failed'))
    }finally{
      setBusy(false)
    }
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
