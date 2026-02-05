rule Bypass_Sample_Pattern1
{
    meta:
        description = "Bypass TEST EAX and conditional jump"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}