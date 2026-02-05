rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? } // Push ebx + ExitProcess call
        $pattern1 = { A1 ?? ?? ?? ?? 85 C0 } // Load value + test eax
        $pattern2 = { 33 DB BA 21 05 00 00 } // Xor ebx + mov edx, 0x00000521

    condition:
        any of them
}