rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D0 52 83 C4 14 52 52 83 C4 14 }  ; ExitProcess call + stack manipulation
        $pattern1 = { E8 ?? ?? ?? ?? 8B D8 83 C4 04 85 C0 }  ; FreeLibrary call + register manipulation
        $pattern2 = { E8 ?? ?? ?? ?? 8B D0 83 C4 04 85 C0 }  ; FreeLibrary call + register manipulation

    condition:
        any of them
}