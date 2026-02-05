rule Bypass_ESI_Check
{
    meta:
        description = "Bypass ESI check"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B 35 88 32 41 00 83 EC 1A 0F 85 }

    condition:
        any of them
}