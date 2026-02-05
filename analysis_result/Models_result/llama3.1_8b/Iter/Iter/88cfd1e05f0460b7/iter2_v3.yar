rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 83 F9 ?? 74 12 } // More general version of the original pattern
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? } // CALL -> TEST EAX -> JE (Strategy A)
        $pattern2 = { 8B CE E8 ?? ?? ?? ?? } // CALL (Strategy B)

    condition:
        any of them
}