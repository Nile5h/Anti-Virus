rule Suspicious_Strings {
    strings:
        $a = "cmd.exe /c"
        $b = "powershell -nop -exec bypass"
        $c = "eval(base64_decode"
    condition:
        any of them
}