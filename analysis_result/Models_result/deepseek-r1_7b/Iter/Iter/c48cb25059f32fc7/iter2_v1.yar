rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip"

    strings:
        $pattern0 = { 85 C0 0F 84 FF ?? ?? ?? ?? ?? ?? }
        $pattern1 = { 83 F8 01 74 12 FF 4D F8 FF }

    condition:
        any of them
}