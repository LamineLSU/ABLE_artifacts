rule Bypass_Test_Jump
{
    meta:
        description = "Bypass TEST EAX, EAX and conditional jump"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}