rule Bypass_ExitProcess_Call
{
    meta:
        description = "Detects code paths leading to ExitProcess call, potential bypass target"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 06 83 C4 ?? 52 FF D0 }
        $pattern1 = { 52 FF D0 5E 5D C3 }
        $pattern2 = { E8 ?? ?? ?? ?? 8B 55 ?? }

    condition:
        all of them
}