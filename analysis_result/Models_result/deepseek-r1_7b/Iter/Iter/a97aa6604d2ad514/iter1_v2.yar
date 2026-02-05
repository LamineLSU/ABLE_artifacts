rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {E8 41 30 25 ??: includes the push ebp and mov ebp, esp instructions}
        $pattern1 = {FF D2 8B ?? ?? ?: a bypass around FFD2 with unique hex values}
        $pattern2 = {something else from another bypass point in the trace}
}