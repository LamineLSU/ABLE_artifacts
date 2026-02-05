rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 8B C0 FF D0 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}