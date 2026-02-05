rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern1+0,action0=skip"

    strings:
        $pattern1 = { 3D ?? ?? ?? 00 0F 82 }

    condition:
        any of them
}