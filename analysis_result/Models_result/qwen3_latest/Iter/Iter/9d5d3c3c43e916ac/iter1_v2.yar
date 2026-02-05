rule ExitProcessCall {
    meta:
        description = "Detects a call to ExitProcess in a specific memory location"
        cape_options = "bp0=$a+0,action0=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
        platform = "Windows"
    strings:
        $a = { FF 15 AC B0 41 00 }  // Hex dump of the call instruction to ExitProcess
    condition:
        $a
}