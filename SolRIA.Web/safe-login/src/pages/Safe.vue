<template>
  <q-page padding>
    <!-- content -->
  </q-page>
</template>

<script>
import { defineComponent, onMounted } from 'vue'
import { useRoute } from "vue-router";

export default defineComponent({
  name: 'PageSafe',
  setup() {
		const $route = useRoute();
    onMounted(() => {
      console.log($route.query);
    })
  }
})
</script>
