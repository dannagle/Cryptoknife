#ifndef GLOBALS_H
#define GLOBALS_H

//BEGIN SW VERSION
#define SW_VERSION "v2.0.1"
//END SW VERSION

//BEGIN FILE VERSION
#define VER_FILEVERSION 2,0,1,0
//END FILE VERSION




#define QDEBUG() qDebug() << __FILE__ << "/" <<__LINE__  <<"(" << __FUNCTION__ << "):"
#define QDEBUGVAR(var)  QDEBUG() << # var <<  var;

#define DATETIMEFORMAT "h:mm:ss.zzz ap"


#endif // GLOBALS_H
