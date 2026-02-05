rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { D8 43 FC ?? ?? ?? ?? }
        $pattern1 = { 7C E1 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}