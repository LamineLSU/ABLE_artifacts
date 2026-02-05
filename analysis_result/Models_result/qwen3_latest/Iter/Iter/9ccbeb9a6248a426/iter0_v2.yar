rule ExitProcessCall {
    meta:
        description = "Detects a call to ExitProcess, often preceded by push ebx"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 53 E8 ?? ?? ?? ?? }  // 53 = push ebx, E8 = call, ?? = displacement (4 bytes)
    condition:
        $a
}