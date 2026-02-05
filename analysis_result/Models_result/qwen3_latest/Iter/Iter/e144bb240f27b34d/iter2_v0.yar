rule pattern1 {
    meta:
        description = "Detects push and call to __crtCorExitProcess (anti-debugging)"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? } // FF 75 08 is push ebp+0x08, E8 is call
    condition:
        $a
}