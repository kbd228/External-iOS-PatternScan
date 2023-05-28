#include <stdio.h>
#include <string.h>
    
#ifndef SCAN_H
#define SCAN_H

template <typename T> static T rpm(task_t targetTask, uintptr_t address){

if(targetTask == MACH_PORT_NULL)
return {0};

T temp;
vm_size_t size;
kern_return_t err = vm_read_overwrite(targetTask, (vm_address_t)address, sizeof(T), (vm_address_t)(void *)&temp, &size);

if(err != KERN_SUCCESS || size != sizeof(T))
return {0};

return temp;
}

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

struct seg_info {
uintptr_t vmaddr;
struct segment_command_64 segcmd;
};

seg_info get_segment(uintptr_t baseAddr, const char *segment, task_t task){
        if(baseAddr && segment && task != MACH_PORT_NULL){

        /* 
        BOOL is64Bit = mh->magic == MH_MAGIC_64 || mh->magic == MH_CIGAM_64;
        uintptr_t cursor = (uintptr_t)mh + (is64Bit ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
        */
        
            struct mach_header_64 mh = rpm<struct mach_header_64>(task, baseAddr);
	   
	    uintptr_t cursor = baseAddr + sizeof(struct mach_header_64);
	    for(uint32_t i = 0; i < mh.ncmds; i++, cursor+=mh.sizeofcmds){
	   
	    struct load_command loadcmd = rpm<struct load_command>(task, (uintptr_t)cursor);
	    
	    if(loadcmd.cmd == LC_SEGMENT_64){
	     struct segment_command_64 segcmd = rpm<struct segment_command_64>(task, (uintptr_t)cursor);
	     
	     if(strcmp(segcmd.segname, segment))
	      return seg_info{0};
	     else
	      return seg_info{ cursor, segcmd };
	     }
	  }
	}
 }

struct sect_info {
 uintptr_t vmaddr;
 struct section_64 seccmd;
 };
 
 sect_info get_section(seg_info info, const char *section, task_t targetTask){
 
  if(!section || targetTask == MACH_PORT_NULL)
    return {0};
    
    uintptr_t cursor = (uintptr_t)info.vmaddr + sizeof(struct segment_command_64);
    for(uint32_t i = 0; i < info.segcmd.nsects; i++, cursor+=sizeof(struct section_64)){
    
    struct section_64 sect = rpm<struct section_64>(targetTask, cursor);
      if(strcmp(sect.sectname, section) == 0)
        return sect_info{cursor, sect};
        
       return {0};
    }
 }

  bool compare(const char *data, const char *pattern, const char *mask){
        for (; *mask; ++mask, ++data, ++pattern)
        {
            if (*mask == 'x' && *data != *pattern)
                return false;
        }

        return !*mask;
    }
    
   uintptr_t scan(sect_info section, const char *pattern, const char *mask)
    {
        const size_t scan_size = strlen(mask);
        
        const uintptr_t sectionStart = section.vmaddr + section.seccmd.offset;
	const uintptr_t sectionEnd = sectionStart + section.seccmd.size;
        for (uint64_t i = 0; i < section.seccmd.size; ++i)
        {
            const uintptr_t current_end = sectionStart + i + scan_size;
            if (current_end > sectionEnd)
                break;

            if (!compare(reinterpret_cast<const char *>(sectionStart + i), pattern, mask))
                continue;

            return sectionStart + i;
        }
        return 0;
    }
    
    // TODO: fix this maybe
    #if 0
    __attribute__((unused)) enum PATTERN_ERROR {
 	INVALID_MH = 1,
 	INVALID_SEGMENT,
 	INVALID_SEQUENCE,
 	INVALID_SECT,
 	KERN_ERR,
 	SIGNATURE_NOT_FOUND
 	};
    
    __attribute__((unused)) uintptr_t patternScan(const struct mach_header *mh, const char *segment, const char *section, uint8_t *sequence, size_t seqSize){
      
       if(!mh)
       return INVALID_MH;
       
       if(!segment)
       return INVALID_SEGMENT;
       
       if(!sequence)
       return INVALID_SEQUENCE;
       
       if(!section)
       return INVALID_SECT;
       
       struct segment_command_64 *seg = get_segment(mh, segment, mach_task_self());
       if(seg){
       
       struct section_64 *sect = get_section(seg, section);
       
       if(sect){
       
       task_t task = mach_task_self();
       uint8_t *buff = (uint8_t *)calloc(sizeof(uint8_t), sect->size);
       size_t size;
       const uintptr_t sectBase = (uintptr_t)sect + sect->offset;
       uintptr_t addr;
       kern_return_t readerr = vm_read(task, (vm_address_t)sectBase, (vm_size_t)sect->size, (vm_offset_t *)buff, (mach_msg_type_number_t *)&size);
       if(readerr == KERN_SUCCESS){
       
      for(uint64_t i = 0; i < size; i++){
          for(int j = 0; j < seqSize; j++){
     
      if(buff[i + j] != sequence[j])
      	break;
      if(j + 1 == seqSize){
         addr = sectBase + i;
         return addr;
         }
      					}
       	 			}
       			}
       		}
	}
}
    #endif //0
    
    #ifdef __cplusplus
    }
    #endif //__cplusplus

#endif // SCAN_H
