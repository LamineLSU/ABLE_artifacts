rule Bypass_Sample_1
{
    meta:
        description = "Bypass conditional jump after TEST"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        all of them
}