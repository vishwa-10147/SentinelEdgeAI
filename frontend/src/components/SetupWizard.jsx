import React, { useEffect, useState } from 'react'
import { apiGet, apiPost, errorMessage } from '../api'
import { AuthCard } from './AuthScreens'

const STEPS = ['Network role', 'Placement', 'Capture interface', 'Response', 'Review']

function Choice({ name, value, current, label, help, disabled, onChange }){
  return (
    <label className={`setup-option${current === value ? ' selected' : ''}${disabled ? ' disabled' : ''}`}>
      <input type="radio" name={name} value={value} checked={current === value} disabled={disabled}
        onChange={()=>onChange(value)} />
      <span>
        <strong>{label}</strong>
        <small>{help}</small>
      </span>
    </label>
  )
}

export default function SetupWizard({ onDone, onCancel }){
  const [info, setInfo] = useState(null)
  const [values, setValues] = useState(null)
  const [step, setStep] = useState(0)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(()=>{
    apiGet('/api/setup', null).then(data=>{
      if(!data){
        setError('Could not load the device settings. Check that you are signed in as an admin.')
        return
      }
      setInfo(data)
      setValues({
        network_role: data.network_role,
        placement: data.placement,
        capture_interface: data.capture_interface,
        response_mode: data.response_mode,
      })
    })
  }, [])

  const set = (key)=>(value)=>setValues({ ...values, [key]: value })

  const finish = async ()=>{
    setBusy(true)
    setError('')
    try{
      await apiPost('/api/setup', values)
      onDone()
    }catch(e){
      setError(errorMessage(e))
    }finally{
      setBusy(false)
    }
  }

  if(!info || !values){
    return (
      <AuthCard title="Set up this device">
        {error ? <div className="auth-error" role="alert">{error}</div> : <p className="auth-hint">Loading…</p>}
        {onCancel && <button className="ghost-button" type="button" onClick={onCancel}>Cancel</button>}
      </AuthCard>
    )
  }

  const { options, interfaces } = info
  const label = (list, value)=>(list.find(o=>o.value === value) || {}).label || value
  const ifaceText = values.capture_interface === 'auto' ? 'Automatic (system default)' : values.capture_interface

  return (
    <AuthCard
      title={info.completed ? 'Device settings' : 'Set up this device'}
      subtitle={`Step ${step + 1} of ${STEPS.length}: ${STEPS[step]}`}
    >
      <ol className="setup-progress" aria-hidden="true">
        {STEPS.map((s, i)=><li key={s} className={i <= step ? 'done' : ''} />)}
      </ol>

      {step === 0 && (
        <div className="setup-options" role="radiogroup" aria-label="Network role">
          {options.roles.map(r=>(
            <Choice key={r.value} name="role" value={r.value} current={values.network_role}
              label={r.label} help={r.help} disabled={!r.available} onChange={set('network_role')} />
          ))}
        </div>
      )}

      {step === 1 && (
        <div className="setup-options" role="radiogroup" aria-label="Placement">
          {options.placements.map(p=>(
            <Choice key={p.value} name="placement" value={p.value} current={values.placement}
              label={p.label} help={p.help} onChange={set('placement')} />
          ))}
        </div>
      )}

      {step === 2 && (
        <div className="setup-options" role="radiogroup" aria-label="Capture interface">
          <Choice name="iface" value="auto" current={values.capture_interface}
            label="Automatic" help="Use the system's default interface." onChange={set('capture_interface')} />
          {interfaces.map(i=>(
            <Choice key={i.name} name="iface" value={i.name} current={values.capture_interface}
              label={i.name}
              help={[i.up ? 'up' : 'down', i.speed_mbps ? `${i.speed_mbps} Mb/s` : null, ...i.addresses].filter(Boolean).join(' · ')}
              onChange={set('capture_interface')} />
          ))}
          <p className="auth-hint">
            {values.placement === 'passive'
              ? 'Pick the port connected to the switch mirror (SPAN) port.'
              : 'Pick the LAN-side port of the bridge.'}
            {' '}The detection engine restarts on its own to use a new interface.
          </p>
        </div>
      )}

      {step === 3 && (
        <div className="setup-options" role="radiogroup" aria-label="Response mode">
          {options.response_modes.map(m=>(
            <Choice key={m.value} name="mode" value={m.value} current={values.response_mode}
              label={m.value.replace('_', ' ')} help={m.help} onChange={set('response_mode')} />
          ))}
          {values.response_mode === 'auto_block' && values.placement === 'passive' && (
            <p className="auth-error" role="note">In passive placement the device cannot block traffic that only passes the mirror port; automatic blocks apply to traffic to and routed through the device.</p>
          )}
          <p className="auth-hint">
            Enforcement is currently <strong>{info.enforcement === 'dry_run' ? 'off (dry run)' : 'on'}</strong>.
            {info.enforcement === 'dry_run' && ' Blocks are recorded but not applied until an administrator sets FIREWALL_DRY_RUN=0 on the device.'}
          </p>
        </div>
      )}

      {step === 4 && (
        <dl className="setup-review">
          <dt>Network role</dt><dd>{label(options.roles, values.network_role)}</dd>
          <dt>Placement</dt><dd>{label(options.placements, values.placement)}</dd>
          <dt>Capture interface</dt><dd>{ifaceText}</dd>
          <dt>Response</dt><dd>{values.response_mode.replace('_', ' ')}</dd>
          <dt>Enforcement</dt><dd>{info.enforcement === 'dry_run' ? 'Dry run (nothing is blocked)' : 'On'}</dd>
        </dl>
      )}

      {error && <div className="auth-error" role="alert">{error}</div>}

      <div className="auth-row setup-nav">
        {step > 0
          ? <button className="ghost-button" type="button" disabled={busy} onClick={()=>setStep(step - 1)}>Back</button>
          : onCancel && <button className="ghost-button" type="button" onClick={onCancel}>Cancel</button>}
        {step < STEPS.length - 1
          ? <button className="primary-button" type="button" onClick={()=>setStep(step + 1)}>Next</button>
          : <button className="primary-button" type="button" disabled={busy} onClick={finish}>{busy ? 'Saving…' : 'Finish setup'}</button>}
      </div>
    </AuthCard>
  )
}
