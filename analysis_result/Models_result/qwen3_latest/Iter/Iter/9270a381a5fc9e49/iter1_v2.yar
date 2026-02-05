rule ExitPoint_Detector
{
    meta:
        description = "Detects the ExitProcess call and related control flow instructions"
        cape_options = "bp0=$call_exit+0,action0=skip,bp1=$call_indirect+0,action1=skip,bp2=$call_indirect_next+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-03-25"

    strings:
        $call_exit = { 8B 55 ?? 8B 06 FF D0 }
        $call_indirect = { 50 E8 ?? ?? ?? ?? }
        $call_indirect_next = { E8 ?? ?? ?? ?? 8B 55 ?? }

    condition:
        any of them
}