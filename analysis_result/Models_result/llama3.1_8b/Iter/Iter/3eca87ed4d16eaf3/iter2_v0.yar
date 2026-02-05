rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test + JE sequence (6 bytes)
        $pattern1 = { FF D2 E8 ?? ?? ?? ?? }  // Call + JE sequence with conditional logic (7 bytes)

    condition:
        any of them
}