"""Save bounded, redacted container error logs from an isolated CI stack."""
from __future__ import annotations
from pathlib import Path
import re
import subprocess

def redact(text: str,env: str) -> str:
    for line in env.splitlines():
        key,sep,value=line.partition('=')
        value=value.strip().strip('\"').strip("'")
        if sep and re.search('TOKEN|PASSWORD|SECRET|KEY',key,re.I) and len(value)>=8:
            text=text.replace(value,'<redacted>')
    text=re.sub(r'(?i)(bearer\s+)[a-z0-9._-]+',r'\1<redacted>',text)
    return re.sub(r'(?i)(visitor_id=)[^;\s]+',r'\1<redacted>',text)

def main() -> None:
    env=Path('.env.commerce').read_text(encoding='utf-8') if Path('.env.commerce').exists() else ''
    result=subprocess.run(['docker','compose','--env-file','.env.commerce','-f','docker-compose.commerce.yml',
        'logs','--no-color','--tail','100','gateway','real-storefront','sandbox-storefront','real-medusa','sandbox-medusa'],
        capture_output=True,text=True,timeout=30,check=False)
    target=Path('artifacts/commerce-runtime-errors.log');target.parent.mkdir(exist_ok=True)
    target.write_text(redact(result.stdout+'\n'+result.stderr,env),encoding='utf-8')
    print('Saved bounded, redacted runtime diagnostics; no database was read.')

if __name__=='__main__':main()
