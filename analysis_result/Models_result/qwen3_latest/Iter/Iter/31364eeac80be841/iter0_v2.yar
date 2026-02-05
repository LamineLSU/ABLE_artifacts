rule ExitProcessCall {
    meta:
        description = "Malware uses ExitProcess to terminate"
        cape_options = "bp0=$a+0,action0=skip,count=0"
        author = "Security Researcher"
    strings:
        $a = { FF 75 08 E8 0B 00 00 00 59 FF 75 08 FF 15 A0 F1 42 00 }
    condition:
        $a
}