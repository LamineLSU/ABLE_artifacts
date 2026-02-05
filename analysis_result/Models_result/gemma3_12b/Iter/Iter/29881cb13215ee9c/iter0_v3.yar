rule Bypass_ConditionalJump
{
    meta:
        description = "Bypass Conditional Jump After TEST"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}