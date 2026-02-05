rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B F0 } // Call to 00419136h + mov esi, eax
        $pattern1 = { E8 ?? ?? ?? ?? 56 }    // Call to 0040684Dh + push esi
        $pattern2 = { 56 FF 15 ?? ?? ?? ?? } // push esi + call ExitProcess

    condition:
        any of them
}