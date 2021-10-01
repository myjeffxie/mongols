#pragma once

#include <dlfcn.h>
#include <memory>
#include <string>

namespace mongols
{

    template <typename T>
    class module
    {
    private:
        typedef T *create_t();
        typedef void destroy_t(T *);

    public:
        module() = delete;
        module(const std::string &path) : m(0), create(0), destroy(0)
        {
            this->m = dlopen(path.c_str(), RTLD_NOW);
            if (this->m)
            {
                this->create = (create_t *)dlsym(m, "create");
                this->destroy = (destroy_t *)dlsym(m, "destroy");
            }
        }
        ~module()
        {
            if (this->m)
            {
                dlclose(this->m);
            }
        }
        template <typename... ARGS>
        void main(ARGS... args)
        {
            T *obj = this->make_obj();
            if (obj)
            {
                obj->handler(args...);
                this->free(obj);
            }
        }

    private:
        T *make_obj()
        {
            return this->create ? this->create() : NULL;
        }
        void free(T *obj)
        {
            this->destroy(obj);
        }

    private:
        void *m;
        create_t *create;
        destroy_t *destroy;
    };

    // template <class T>
    // class module
    // {
    // public:
    //     module()
    //         : handle(NULL), create(NULL), destroy(NULL), path(), creator(false)
    //     {
    //     }

    //     module(const std::string &path)
    //         : handle(NULL), create(NULL), destroy(NULL), path(path), creator(false)
    //     {
    //         this->init();
    //     }

    //     module(const module<T> &other)
    //         : handle(other.handle), create(other.create), destroy(other.destroy), path(other.path), creator(false)
    //     {
    //     }

    //     module<T> &operator=(const module<T> &right)
    //     {
    //         if (this == &right)
    //             return *this;
    //         this->handle = right.handle;
    //         this->create = right.create;
    //         this->destroy = right.destroy;
    //         this->path = right.path;
    //         this->creator = false;
    //         return *this;
    //     }

    //     virtual ~module()
    //     {
    //         if (this->handle != NULL && this->creator)
    //         {
    //             dlclose(this->handle);
    //         }
    //     }

    //     void set_module(const std::string &path)
    //     {
    //         this->path = path;
    //         this->init();
    //     }

    //     const std::string &get_module() const
    //     {
    //         return this->path;
    //     }

    //     bool is_ok() const
    //     {
    //         return this->creator;
    //     }

    //     template <typename... Args>
    //     std::shared_ptr<T> make_obj(Args... args)
    //     {
    //         if (!this->creator)
    //         {
    //             return nullptr;
    //         }

    //         T *obj = this->create(args...);
    //         destroy_t *d = this->destroy;
    //         return std::shared_ptr<T>(obj,
    //                                   [&](T *p) {
    //                                       d(p);
    //                                   });
    //     }

    // private:
    //     typedef T *create_t();
    //     typedef void destroy_t(T *);
    //     void *handle;
    //     create_t *create;
    //     destroy_t *destroy;
    //     std::string path;
    //     bool creator;

    //     void init()
    //     {
    //         this->handle = dlopen(this->path.c_str(), RTLD_NOW);
    //         if (this->handle)
    //         {
    //             this->create = (create_t *)dlsym(this->handle, "create");
    //             this->destroy = (destroy_t *)dlsym(this->handle, "destroy");
    //             if (this->create && this->destroy)
    //             {
    //                 this->creator = true;
    //             }
    //         }
    //     }
    // };
} // namespace mongols
