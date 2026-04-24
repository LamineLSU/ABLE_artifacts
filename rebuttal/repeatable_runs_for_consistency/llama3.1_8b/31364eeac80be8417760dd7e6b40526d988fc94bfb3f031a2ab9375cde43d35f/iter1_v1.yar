rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip"

    strings:
        $pattern0 = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? 83 F8 01 74 12 }  // CALL + TEST EAX + JE

    condition:
        any of them
}