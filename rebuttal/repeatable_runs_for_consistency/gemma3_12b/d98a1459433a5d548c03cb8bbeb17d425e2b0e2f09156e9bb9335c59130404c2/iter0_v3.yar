rule Bypass_Call_0084A12C
{
    meta:
        description = "Bypass call to 0084A12Ch"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 53 FF 15 2C A1 ?? ?? ?? ?? }

    condition:
        any of them
}