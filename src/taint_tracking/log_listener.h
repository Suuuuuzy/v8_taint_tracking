#ifndef LOG_LISTENER_H
#define LOG_LISTENER_H

#include "logrecord.capnp.h"

namespace tainttracking {

  /* Not thread safe */
  class LogListener {
  public:
    inline virtual ~LogListener() {}
    virtual void OnLog(const ::TaintLogRecord::Reader&) = 0;
  };

  void RegisterLogListener(std::unique_ptr<LogListener> listener);
}

#endif
