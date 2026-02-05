rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+8,action0=skip"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? }

    condition:
        any of them
}