<template>
    <v-card >
      <v-navigation-drawer
          id="main-sidebar"
      >
        <v-list density="compact" nav>
          <v-list-item
              v-for="item in items"
              :key="item.title"
              :to="item.to"
              :prepend-icon="item.icon"
              :title="item.title"
              color="light-blue-darken-4"
              link
          />
        </v-list>
      </v-navigation-drawer>
    </v-card>
  </template>
  <script lang="ts">
  export default {
    name: "side-bar",
    data: () => ({
      items: [
        {
          title: "Home",
          icon: "mdi-home-circle-outline",
          to: "/"
        },
      ]
    }),
  }
  </script>
  <style>
  #main-sidebar{
    box-shadow:1px 0 20px rgba(0,0,0,.08);
    -webkit-box-shadow:1px 0 20px rgba(0,0,0,.08);
  }
  </style>