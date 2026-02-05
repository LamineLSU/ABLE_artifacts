rule Bypass_Sample_Evolved_A
{
    meta:
        description = "Evasion bypass rule - evolved (Strategy A)"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }

    condition:
        any of them
}