rule Bypass_Sample_Pattern3
{
    meta:
        description = "Bypass by skipping the call to 0041EB47"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 56 56 6A 36 6A 00 51 51 E8 ?? ?? ?? ?? }

    condition:
        any of them
}