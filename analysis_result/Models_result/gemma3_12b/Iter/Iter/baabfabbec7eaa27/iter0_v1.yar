rule Bypass_Sample_Call1
{
    meta:
        description = "Evasion bypass rule - Skip call 00E1A12Ch"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 8B 85 F0 FE FF FF }

    condition:
        any of them
}