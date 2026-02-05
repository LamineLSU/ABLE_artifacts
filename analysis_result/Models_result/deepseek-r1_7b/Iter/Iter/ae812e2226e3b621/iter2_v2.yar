rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using call and push instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B CE E8 25 05 00 00 ?? } // Push and call instruction from trace //1
        $pattern1 = { FF 15 AC B1 E8 C8 FF FF ?? } // Push and call instruction from trace //3
        $pattern2 = { FF 15 40 E1 E8 C8 FF FF ?? } // Push and call instruction from trace //5

    condition:
        any of them
}