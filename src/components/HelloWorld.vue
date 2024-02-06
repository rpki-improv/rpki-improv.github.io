<template>
  <v-container class="">
    <v-responsive class="align-center fill-height">
      <div class="text-h4 text--primary pa-2">TBD TABLE TITLE</div>

      <v-card
      class="mx-auto mt-2 pa-3"
        elevation="2"
      >
      <template v-slot:text>
        <v-text-field
          v-model="search"
          label="Search"
          prepend-inner-icon="mdi-magnify"
          single-line
          variant="outlined"
          hide-details
        ></v-text-field>
      </template>

        <v-data-table :items="items"
          class="pa-3"
          :search="search"
          :headers="this.headers"
        >
      </v-data-table>

      </v-card>
    </v-responsive>
  </v-container>
</template>

<script lang="ts">
const headers = [
          {
            align: 'start',
            key: 'id',
            sortable: false,
            title: 'Id',
          },
          {
            key: 'domain',
            sortable: true,
            title: 'Domain',
          }
        ]
  export default {
    data()  {
      return {
        search: "",
        items : [
          {
            id: 1,
            domain: 'test 1 domain'
          },
          {
            id: 1,
            domain: 'test 2 domain'
          },
          {
            id: 1,
            domain: 'test 4 domain'
          },
          {
            id: 1,
            domain: 'test 3 domain'
          },
          {
            id: 1,
            domain: 'test 5 domain'
          },
          {
            id: 1,
            domain: 'test 6 domain'
          },
          {
            id: 1,
            domain: 'test 8 domain'
          },
          {
            id: 1,
            domain: 'test 7 domain'
          },
          {
            id: 1,
            domain: 'test 9 domain'
          },
          {
            id: 1,
            domain: 'test 10 domain'
          },{
            id: 1,
            domain: 'test 11 domain'
          },
        ]
      }
    }
  }
</script>
