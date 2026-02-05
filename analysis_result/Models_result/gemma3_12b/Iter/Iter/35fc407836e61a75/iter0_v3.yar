rule Bypass_Sample_1
{
    meta:
        description = "Bypass potential VM detection call"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? E8 C8 FF FF FF }

    condition:
        any of them
}