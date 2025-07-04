/* eslint-disable */

// @ts-nocheck

// noinspection JSUnusedGlobalSymbols

// This file was automatically generated by TanStack Router.
// You should NOT make any changes in this file as it will be overwritten.
// Additionally, you should also exclude this file from your linter and/or formatter to prevent it from being checked or modified.

import { Route as rootRouteImport } from './routes/__root'
import { Route as IndexRouteImport } from './routes/index'
import { Route as SignUpIndexRouteImport } from './routes/sign-up/index'
import { Route as SignInIndexRouteImport } from './routes/sign-in/index'
import { Route as HomeIndexRouteImport } from './routes/home/index'

const IndexRoute = IndexRouteImport.update({
  id: '/',
  path: '/',
  getParentRoute: () => rootRouteImport,
} as any)
const SignUpIndexRoute = SignUpIndexRouteImport.update({
  id: '/sign-up/',
  path: '/sign-up/',
  getParentRoute: () => rootRouteImport,
} as any)
const SignInIndexRoute = SignInIndexRouteImport.update({
  id: '/sign-in/',
  path: '/sign-in/',
  getParentRoute: () => rootRouteImport,
} as any)
const HomeIndexRoute = HomeIndexRouteImport.update({
  id: '/home/',
  path: '/home/',
  getParentRoute: () => rootRouteImport,
} as any)

export interface FileRoutesByFullPath {
  '/': typeof IndexRoute
  '/home': typeof HomeIndexRoute
  '/sign-in': typeof SignInIndexRoute
  '/sign-up': typeof SignUpIndexRoute
}
export interface FileRoutesByTo {
  '/': typeof IndexRoute
  '/home': typeof HomeIndexRoute
  '/sign-in': typeof SignInIndexRoute
  '/sign-up': typeof SignUpIndexRoute
}
export interface FileRoutesById {
  __root__: typeof rootRouteImport
  '/': typeof IndexRoute
  '/home/': typeof HomeIndexRoute
  '/sign-in/': typeof SignInIndexRoute
  '/sign-up/': typeof SignUpIndexRoute
}
export interface FileRouteTypes {
  fileRoutesByFullPath: FileRoutesByFullPath
  fullPaths: '/' | '/home' | '/sign-in' | '/sign-up'
  fileRoutesByTo: FileRoutesByTo
  to: '/' | '/home' | '/sign-in' | '/sign-up'
  id: '__root__' | '/' | '/home/' | '/sign-in/' | '/sign-up/'
  fileRoutesById: FileRoutesById
}
export interface RootRouteChildren {
  IndexRoute: typeof IndexRoute
  HomeIndexRoute: typeof HomeIndexRoute
  SignInIndexRoute: typeof SignInIndexRoute
  SignUpIndexRoute: typeof SignUpIndexRoute
}

declare module '@tanstack/react-router' {
  interface FileRoutesByPath {
    '/': {
      id: '/'
      path: '/'
      fullPath: '/'
      preLoaderRoute: typeof IndexRouteImport
      parentRoute: typeof rootRouteImport
    }
    '/sign-up/': {
      id: '/sign-up/'
      path: '/sign-up'
      fullPath: '/sign-up'
      preLoaderRoute: typeof SignUpIndexRouteImport
      parentRoute: typeof rootRouteImport
    }
    '/sign-in/': {
      id: '/sign-in/'
      path: '/sign-in'
      fullPath: '/sign-in'
      preLoaderRoute: typeof SignInIndexRouteImport
      parentRoute: typeof rootRouteImport
    }
    '/home/': {
      id: '/home/'
      path: '/home'
      fullPath: '/home'
      preLoaderRoute: typeof HomeIndexRouteImport
      parentRoute: typeof rootRouteImport
    }
  }
}

const rootRouteChildren: RootRouteChildren = {
  IndexRoute: IndexRoute,
  HomeIndexRoute: HomeIndexRoute,
  SignInIndexRoute: SignInIndexRoute,
  SignUpIndexRoute: SignUpIndexRoute,
}
export const routeTree = rootRouteImport
  ._addFileChildren(rootRouteChildren)
  ._addFileTypes<FileRouteTypes>()
