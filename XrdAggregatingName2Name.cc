


 
/******************************************************************************/
/*                                                                            */
/*                     X r d O u c N a m 2 N a m e . c c                      */
/*                                                                            */
/* (c) 2006 by the Board of Trustees of the Leland Stanford, Jr., University  */
/*                            All Rights Reserved                             */
/*   Produced by Andrew Hanushevsky for Stanford University under contract    */
/*              DE-AC02-76-SFO0515 with the Department of Energy              */
/******************************************************************************/
  
// This file implements an instance of the XrdOucName2Name abstract class.

#include <errno.h>

#include "XrdSys/XrdSysError.hh"
#include "XrdOuc/XrdOucName2Name.hh"
#include "XrdSys/XrdSysPlatform.hh"



XrdOucName2Name *XrdOucgetName2Name(XrdOucgetName2NameArgs);




class XrdAggregatingN2N : public XrdOucName2Name
{
  friend XrdOucName2Name *XrdOucgetName2Name(XrdOucgetName2NameArgs);

public:

virtual int lfn2pfn(const char *lfn, char *buff, int blen);

virtual int lfn2rfn(const char *lfn, char *buff, int blen);

virtual int pfn2lfn(const char *lfn, char *buff, int blen);

            XrdAggregatingN2N(XrdSysError *erp, const char *lpfx, const char *rpfx);

private:
int concat_fn(const char *prefix, int  pfxlen,
              const char *path,  char *buffer, int blen);

XrdSysError *eDest;
char        *LocalRoot;
int          LocalRootLen;
char        *RemotRoot;
int          RemotRootLen;
char         madpfx[512];
int          madpfxlen;
};
 
/******************************************************************************/
/*                        I m p l e m e n t a t i o n                         */
/******************************************************************************/
/******************************************************************************/
/*                           C o n s t r u c t o r                            */
/******************************************************************************/
  
XrdAggregatingN2N::XrdAggregatingN2N(XrdSysError *erp,
				     const char *lpfx,
				     const char *rpfx):
  madpfxlen(0)
{
   eDest = erp;

// Local root must not have any trailing slahes
//
   if (!lpfx) {LocalRoot = 0; LocalRootLen = 0;}
      else if (!(LocalRootLen = strlen(lpfx))) LocalRoot = 0;
              else {LocalRoot = strdup(lpfx);
                    while(LocalRootLen && LocalRoot[LocalRootLen-1] == '/')
                         {LocalRootLen--; LocalRoot[LocalRootLen] = '\0';}
                   }

// Remote root must not have any trailing slahes
//
   if (!rpfx) {RemotRoot = 0; RemotRootLen = 0;}
      else if (!(RemotRootLen = strlen(rpfx))) RemotRoot = 0;
              else {RemotRoot = strdup(rpfx);
//                    while(RemotRootLen && RemotRoot[RemotRootLen-1] == '/')
//                          {RemotRootLen--; RemotRoot[RemotRootLen] = '\0';}
                   }

   madpfx[0] = '\0';
}

/******************************************************************************/
/*                               l f n 2 p f n                                */
/******************************************************************************/
  
int XrdAggregatingN2N::lfn2pfn(const char *lfn, char  *buff, int blen)
{
    char buff1[1024];
  
    strcpy(buff1, lfn);

    // If the mad local prefix is not present in lfn (i.e. meta-global query)
    // we add it
    // Doing so, the local storage can be queried with and without
    // the madpfx

    if ( strstr(lfn, madpfx) != lfn ) {
      if (concat_fn(madpfx, madpfxlen, lfn, buff1, 1024))
        return eDest->Emsg("glp",-ENAMETOOLONG,"generate local path step 1 lfn=",lfn);
    }

    if (concat_fn(LocalRoot, LocalRootLen, buff1, buff, blen))
       return eDest->Emsg("glp",-ENAMETOOLONG,"generate local path step 2 lfn=",lfn);

    return 0;
}

/******************************************************************************/
/*                               l f n 2 r f n                                */
/******************************************************************************/
  
int XrdAggregatingN2N::lfn2rfn(const char *lfn, char  *buff, int blen)
{
    char buff1[1024];
    char buff2[1024];
    char *slash = "/";
 
    strcpy(buff1, lfn);

    // If the mad local prefix is present in lfn (i.e. meta-global query)
    // we strip it
    // Doing so, the local mps scripts are autonomous, and can exploit their
    //  own name translation, for both lfn and rfn
    // But they are sure they get only global names, not local cluster aliases

    if ( strstr(lfn, madpfx) == lfn ) {
	strcpy(buff1, lfn+madpfxlen);
    }
    else strcpy(buff1, lfn);


   if (concat_fn(RemotRoot, RemotRootLen, buff1, buff, blen))
      return eDest->Emsg("grp",-ENAMETOOLONG,"generate remote path step 3 lfn=",lfn);
   return 0;
}

/******************************************************************************/
/*                             c o n c a t _ f n                              */
/******************************************************************************/
  
int XrdAggregatingN2N::concat_fn(const char *prefix, // String to prefix path
                         const int   pfxlen, // Length of prefix string
                         const char *path,   // String to suffix prefix
                               char *buffer, // Resulting buffer
                               int   blen)   // The buffer length
{
   int addslash = (*path != '/');
   int pathlen  = strlen(path);

   if ((pfxlen + addslash + pathlen) >= blen) return -1;

   if (pfxlen) {strcpy(buffer, prefix); buffer += pfxlen;}
   if (addslash) {*buffer = '/'; buffer++;}
   strcpy(buffer, path);

   eDest->Say("XrdAggregatingN2N processing. buff='",buffer,"'");
   return 0;
}

/******************************************************************************/
/*                               p f n 2 l f n                                */
/******************************************************************************/
  
int XrdAggregatingN2N::pfn2lfn(const char *pfn, char  *buff, int blen)
{
    char *tp;

    if (!LocalRoot
    ||  strncmp(pfn, LocalRoot, LocalRootLen) 
    ||  pfn[LocalRootLen] == '/')
            tp = (char *)pfn;
       else tp = (char *)(pfn+LocalRootLen);

    if (strlcpy(buff, tp, blen) >= (unsigned int)blen) return ENAMETOOLONG;

    if (!strlen(madpfx)
    || strncmp(pfn, madpfx, madpfxlen))
            tp = (char *)buff;
       else tp = (char *)(buff+madpfxlen);

    if (strlcpy(buff, tp, blen) >= (unsigned int)blen) return ENAMETOOLONG;
    return 0;
}



/******************************************************************************/
/*                    X r d O u c g e t N a m e 2 N a m e                     */
/******************************************************************************/
  
XrdOucName2Name *XrdOucgetName2Name(XrdOucgetName2NameArgs)
{
   XrdAggregatingN2N *inst = new XrdAggregatingN2N(eDest, lroot, rroot);
   if (parms) eDest->Say("++++++ XrdAggregatingN2N initializing. Local lfn prefix '",parms,"'.");
   else
     eDest->Say("++++++ XrdAggregatingN2N initializing. Local lfn prefix is null");

   if (rroot) eDest->Say("++++++ XrdAggregatingN2N initializing. Remote root '",rroot,"'.");
   else
     eDest->Say("++++++ XrdAggregatingN2N initializing. Remote root is null");

   if (parms) {
     strcpy(inst->madpfx, parms);
     inst->madpfxlen = strlen(parms);
   }

   return (XrdOucName2Name *)inst;
}
