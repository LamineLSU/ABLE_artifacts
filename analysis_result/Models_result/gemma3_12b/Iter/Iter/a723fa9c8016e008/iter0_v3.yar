rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass rule - Test EAX, EAX and Je bypass"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}