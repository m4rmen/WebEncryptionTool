'use client';
import { useState } from 'react';
import { encryptFileChunked, decryptFileChunked } from '@/lib/crypto/file';
import { downloadBlob } from '@/lib/storage/download';
const zxcvbn = require("zxcvbn");

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [progress, setProgress] = useState(0);
  const [pwStrength, setPwStrength] = useState<number | null>(null);
  const [busy, setBusy] = useState<'enc'|'dec'|null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const pwHandleChange = (event: React.ChangeEvent<HTMLInputElement>) =>{
    const { value } = event.target;
    setPassword(value);
    if (!checkFileEncrypted()) {
      checkPasswordStrength();
    }
  }

  const checkPasswordStrength = () => {
    if (!password) return;
    const result = zxcvbn(password);
    setPwStrength(result.score);
    if (result.score < 3) {
      setMessage('Password is weak. Please choose a stronger password.');
    } else {
      setMessage("Password is strong.");
    }
  }

  const checkFileEncrypted = () => {
    if (!file) return false;
    const fileExtension = file.name.split('.').pop();
    return fileExtension === "enc";
  };

  return (
    <main className="max-w-xl mx-auto p-6 space-y-4">
      <h1 className="text-2xl font-semibold mt-8">Web Encryption Tool</h1>

      <input type="file" className="w-full px-4 py-2 rounded bg-foreground text-background cursor-pointer" onChange={e => setFile(e.target.files?.[0] ?? null)} />
      <input
        type="password"
        placeholder="File Password"
        className="border rounded px-3 py-2 w-full "
        value={password}
        onChange={e => pwHandleChange(e)}
      />
      <div className={`h-2 rounded overflow-hidden ${(file && !checkFileEncrypted()) ? 'bg-black/10' : ''}`}>
        <div className="h-full bg-progress" style={{ width: `${Math.round(pwStrength ? (pwStrength/3) * 100 : 0)}%` }} />
      </div>
      <div className="flex gap-3">
        <button
          type="button"
          disabled={!file || !password || !!busy || checkFileEncrypted()}
          className={`px-4 py-2 rounded border ${(!file || !password || !!busy || checkFileEncrypted()) ? 'opacity-50 cursor-not-allowed' : 'bg-foreground text-background cursor-pointer'}`}
          onClick={async () => {
            if (!file) return;
            try {
              setMessage(null);
              setBusy('enc'); setProgress(0);
              const out = await encryptFileChunked(file, password, setProgress);
              downloadBlob(out, `${file.name}.enc`);
              setMessage('File encrypted and downloaded.');
            } catch (e: any) {
              console.error(e);
              setMessage(e?.message ?? 'Encryption failed');
            } finally {
              setBusy(null);
            }
          }}
        >
          {busy === 'enc' ? 'Encrypting…' : 'Encrypt'}
        </button>

        <button
          type="button"
          disabled={!file || !password || !!busy || !checkFileEncrypted()}
          className={`px-4 py-2 rounded border ${(!file || !password || !!busy || !checkFileEncrypted()) ? 'opacity-50 cursor-not-allowed' : 'bg-foreground text-background cursor-pointer'}`}
          onClick={async () => {
            if (!file) return;
            try {
              setMessage(null);
              setBusy('dec'); setProgress(0);
              const buf = new Uint8Array(await file.arrayBuffer());
              const { fileName, data } = await decryptFileChunked(buf, password, setProgress);
              downloadBlob(data, fileName);
              setMessage('File decrypted and downloaded.');
            } catch (e: any) {
              console.error(e);
              if (e?.name === 'WrongPasswordError') {
                alert('Password is incorrect. Please try again.');
              } else {
                setMessage(e?.message ?? 'Decryption failed');
              }
            } finally {
              setBusy(null);
            }
          }}
        >
          {busy === 'dec' ? 'Decrypting…' : 'Decrypt'}
        </button>
      </div>

      <div className="h-2 rounded overflow-hidden">
        <div className="h-full bg-foreground" style={{ width: `${Math.round(progress * 100)}%` }} />
      </div>
      {message && (
        <div className="text-sm text-center text-foreground/80" role="status">{message}</div>
      )}
    </main>
  );
}
