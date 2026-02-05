rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? } // Direct call to ExitProcess (API_CHECK)
        $pattern1 = { 6A 00 E8 ?? ?? ?? ?? } // Push 00000000h followed by call (conditional logic)
        $pattern2 = { E8 ?? ?? ?? ?? CC } // Call to ExitProcess followed by int3 (debug check)

    condition:
        all of them
}