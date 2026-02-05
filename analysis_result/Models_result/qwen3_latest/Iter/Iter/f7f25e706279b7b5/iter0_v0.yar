rule HeapManagement
{
    meta:
        description = "Detects heap management functions via API calls"
        cape_options = "bp0=$call1+0,action0=skip,bp1=$call2+0,action1=skip,bp2=$call3+0,action2=skip,count=0"
        author = "YourName"

    strings:
        $call1 = { 8B 16 50 51 FF D2 }  // Call to RtlAllocateHeap
        $call2 = { 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? }  // Call to RtlFreeHeap with surrounding instructions
        $call3 = { 50 E8 ?? ?? ?? ?? }  // Call to RtlFreeHeap with displacement

    condition:
        any of them
}