rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 ?? ?? ?? ?? }  // Push + Call to ExitProcess (offsets wildcards)
        $pattern1 = { E8 ?? ?? ?? ?? 6A 00 }  // Call to 00410E2Eh + Push (offsets wildcards)
        $pattern2 = { E8 ?? ?? ?? ?? CC }     // Call to ExitProcess + int3 (offsets wildcards)

    condition:
        any of them
}