rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? EA AA CA EA EC FC CA AD DC EE AC AE AC DE FF EE DE CC EE EA EB EA 6A AC DE ?? EE EE AC ED FF CE E8 CD BE AE DE EA }
        $pattern1 = { FF 15 3C ?? EA AA CA EA FF CA EE CE EE AC AE AC DE FF EE DE CC EE EA EB EA FF AF 15 AD 3C CD BE EE EC DE DE EA AD EE }
        $pattern2 = { FF 40 ?? EA AA CA EA ED CA EE CE EE AC AE AC DE FF EE DE CC EE EA EB EA FF AF 40 CD BE AE EE CD DE EA AD EE }

    condition:
        any_of them
}