rule Bypass_Sample_Evolved
{
    meta:
        description = "RDTSC timing-based bypass of absolute exit point"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,capture0=0,capture1=0"

    strings:
        $pattern0 = { 20 }
        $pattern1 = { 20 FF EE CE }

    condition:
        any of them
}